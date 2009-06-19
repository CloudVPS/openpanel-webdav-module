#include <grace-coreapi/module.h>
#include <grace/filesystem.h>
#include <grace/system.h>

#ifdef __FLAVOR_LINUX_DEBIAN
	#define SVCNAME "apache2"
	#define CONFDIR "/etc/apache2/openpanel.d"
#else
	#define SVCNAME "httpd"
	#define CONFDIR "/etc/httpd/openpanel.d"
#endif

// --------------------------------------------------------------------------
// The class handling Domain:WebDAV objects as well as its
// WebDAV:User children.
// --------------------------------------------------------------------------
class WebDAV : public CoreClass
{
public:
	// ======================================================================
	// Constructor
	// ======================================================================
	WebDAV (void) : CoreClass ("Domain:WebDAV")
	{
		// We're using allchildren=true because we want to write the
		// webdav htpasswd file in one go. So we'll swallow requests
		// for WebDAV:User from this class.
		alias ("WebDAV:User");
	}
	
	// ======================================================================
	// Destructor
	// ======================================================================
	~WebDAV (void)
	{
	}
	
	// ======================================================================
	// Loads the shares.conf file and parses it into a dictionary of
	// (integer) port numbers indexed by vhost name.
	// ======================================================================
	value *loadConf (void)
	{
		returnclass (value) res retain;
		string raw = fs.load ("/etc/webdav/shares.conf");
		value lines = strutil::splitlines (raw);
		foreach (line, lines)
		{
			value splt = strutil::splitspace (line);
			if (splt.count() != 2) continue;
			if (splt[0] == 0) continue;
			res[splt[1].sval()] = splt[0].ival();
		}
		
		return &res;
	}
	
	// ======================================================================
	// Write a new shares.conf through authd.
	// ======================================================================
	bool saveConf (value &conf)
	{
		file f;
		
		if (! f.openwrite ("shares.conf"))
		{
			error (CoreModule::E_OTHER, "I/O error");
			return false;
		}
		
		foreach (node, conf)
		{
			f.writeln ("%i %s" %format (node, node.id()));
		}
		f.close ();
		
		if (!authd.installFile ("shares.conf", "/etc/webdav"))
		{
			error (CoreModule::E_OTHER, "Error installing shared.conf");
			return false;
		}
		return true;
	}
	
	// ======================================================================
	// Find the lowest free port to provision a new share
	// ======================================================================
	int findPort (const value &conf)
	{
		int port = 800;
		
		bool portfound = true;
		
		// This could be so much prettier
		while (portfound == true)
		{
			portfound = false;
			foreach (node, conf)
			{
				if (node.ival() == port)
				{
					portfound = true;
					++port;
					break;
				}
			}
		}
		return port;
	}
	
	// ======================================================================
	// Create the directory structure for the share. One part goes in
	// /var/webdav and contains the apache configuration, pidfile
	// and errorlog. The other part is created in the user home directory.
	// ======================================================================
	bool createDirs (void)
	{
		if (! fs.exists ("/var/webdav/%s" %format (id)))
		{
			if (! authd.makeDir ("/var/webdav/%s" %format (id))) return false;
			if (! authd.makeDir ("/var/webdav/%s/conf" %format (id))) return false;
			if (! authd.makeDir ("/var/webdav/%s/logs" %format (id))) return false;
			if (! authd.makeDir ("/var/webdav/%s/run" %format (id))) return false;
		}
		
		authd.makeUserDir (owner, "0711", "sites");
		authd.makeUserDir (owner, "0750", "sites/%s" %format (id));
		authd.makeUserDir (owner, "0700", "sites/%s/conf" %format (id));
		authd.makeUserDir (owner, "0700", "sites/%s/var" %format (id));
		authd.makeUserDir (owner, "0750", "sites/%s/data" %format (id));
		return true;
	}
	
	bool writeVirtualHost (int port)
	{
		file f;
		string fname = "%s.conf" %format (id);
		
		if (! f.openwrite (fname))
		{
			error (CoreModule::E_OTHER, "Could not write vhost file");
			return false;
		}
		
		try
		{
			f.puts ("<VirtualHost *:80>\n"
					"  ServerAdmin webmaster@%s\n"
					"  DocumentRoot /var/www/html\n"
					"  ServerName %{0}s\n"
					%format (id));
			
			value aliases = listAliases (env);
			foreach (alias, aliases)
			{
				f.writeln ("  ServerAlias %s" %format (alias));
			}
			
			f.puts ("  <Location />\n"
					"    ProxyPass http://localhost:%i/\n"
					"  </Location>\n" 
					"</VirtualHost>\n" %format (port));
			
			f.close ();
		}
		catch (exception e)
		{
			f.close ();
			error (CoreModule::E_OTHER, "Exception: %s" %format (e.description));
			return false;
		}
		
		if (! authd.installFile (fname, CONFDIR))
		{
			error (CoreModule::E_AUTHD, authd.error);
			return false;
		}
		
		if (! authd.reloadService (SVCNAME))
		{
			error (CoreModule::E_AUTHD, authd.error);
			return false;
		}
		
		return true;
	}
	
	// ======================================================================
	// Handler for the update command. Regardless of context, this will
	// be called for an update to either the root Domain:WebDAV object
	// or any of its WebDAV:User children.
	// ======================================================================
	bool update (void)
	{
		const value &list = listChildren ("WebDAV:User");
		file f (">webdav.passwd");

		foreach (user, list)
		{
			f.writeln ("%s:%s" %format (user["metaid"],user["password"]));
		}
		f.close ();
		
		string dpath = "sites/%s/conf" %format (id);
		if (! authd.installUserFile ("webdav.passwd", dpath, owner))
		{
			error (CoreModule::E_OTHER, "Error installing webdav.passwd");
			return false;
		}
		return true;
	}
	
	// ======================================================================
	// Handler for the create command
	// ======================================================================
	bool create (void)
	{
		// We handle the update of the password file from update()
		if (requestedClass == "WebDAV:User")
		{
			return update();
		}
		
		// Load the httpd.conf tempate file
		string tmpl = fs.load ("/etc/webdav/template.conf");
		
		// Get information about the object owner
		value pw = core.userdb.getpwnam (owner);
		if (! pw)
		{
			error (CoreModule::E_OTHER, "Unknown user");
			return false;
		}
		
		// Get information about the group belonging to the owner's groupid.
		value gr = core.userdb.getgrgid (pw["gid"].uval());
		if (! gr)
		{
			error (CoreModule::E_OTHER, "Unknwon user group");
			return false;
		}
		
		// So that we now have a proper groupname
		string group = gr["groupname"];
		
		// Location of the root folder
		string docroot = "%s/sites/%s" %format (pw["home"],id);
		
		value conf = loadConf();
		int port = findPort (conf);
		conf[id] = port;
		if (! saveConf (conf)) return false;
		
		// Set up the environment for valueparse
		value senv = $("user",owner)->
					 $("group",group)->
					 $("docroot",docroot)->
					 $("vhost",id)->
					 $("port",port);
					 
		tmpl = strutil::valueparse (tmpl, senv);
		
		fs.save ("httpd.conf", tmpl);
		
		if (! createDirs())
		{
			error (CoreModule::E_OTHER, "Could not create dirs");
			return false;
		}
		
		string destdir = "/var/webdav/%s/conf" %format (id);
		if (! authd.installFile ("httpd.conf", destdir))
		{
			error (CoreModule::E_OTHER, "Could not install httpd.conf");
			return false;
		}
		
		if (! writeVirtualHost (port)) return false;
		
		if (! authd.reloadService ("webdav"))
		{
			error (CoreModule::E_OTHER, "Could not restart webdav service");
			return false;
		}
		
		return true;
	}
	
	bool remove (void)
	{
		if (requestedClass == "WebDAV:User")
		{
			return update();
		}
		
		value conf = loadConf();
		conf[id] = 0;
		if (! saveConf (conf)) return false;
		
		if (! authd.reloadService ("webdav"))
		{
			error (CoreModule::E_OTHER, "Could not restart webdav service");
			return false;
		}
		
		authd.deleteDir ("/var/webdav/%s" %format (id));
		authd.deleteFile (CONFDIR "/%s.conf" %format (id));
		authd.reloadService (SVCNAME);
		return true;
	}
};

class WebDAVModule : public CoreModule
{
public:
	WebDAVModule (void)
		: CoreModule ("WebDAV.module")
	{
	}
	
	~WebDAVModule (void)
	{
	}
	
	WebDAV webdav;
};

IMPLEMENT (WebDAVModule);

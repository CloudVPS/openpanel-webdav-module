#include <grace-coreapi/module.h>
#include <grace/filesystem.h>
#include <grace/system.h>

class WebDAV : public CoreClass
{
public:
	WebDAV (void) : CoreClass ("Domain:WebDAV")
	{
		// We're using allchildren=true because we want to write the
		// webdav htpasswd file in one go. So we'll swallow requests
		// for WebDAV:User from this class.
		alias ("WebDAV:User");
	}
	
	~WebDAV (void)
	{
	}
	
	value *loadconf (void)
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
	
	bool saveconf (value &conf)
	{
		file f;
		if (! f.openwrite ("shares.conf")) return false;
		
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
	
	int findport (const value &conf)
	{
		int port = 800;
		
		bool portfound = true;
		
		while (portfound == true)
		{
			portfound = false;
			foreach (node, conf)
			{
				if (node.ival() == port)
				{
					portfound = true;
					break;
				}
			}
			++port;
		}
		return port;
	}
	
	bool createdirs (const string &vhost, const string &user)
	{
		if (! fs.exists ("/var/webdav/%s" %format (vhost)))
		{
			if (! authd.makeDir ("/var/webdav/%s" %format (vhost))) return false;
			if (! authd.makeDir ("/var/webdav/%s/conf" %format (vhost))) return false;
			if (! authd.makeDir ("/var/webdav/%s/logs" %format (vhost))) return false;
			if (! authd.makeDir ("/var/webdav/%s/run" %format (vhost))) return false;
		}
		
		authd.makeUserDir (user, "0711", "www");
		authd.makeUserDir (user, "0750", "www/%s" %format (vhost));
		authd.makeUserDir (user, "0700", "www/%s/conf" %format (vhost));
		authd.makeUserDir (user, "0700", "www/%s/var" %format (vhost));
		authd.makeUserDir (user, "0750", "www/%s/data" %format (vhost));
		return true;
	}
	
	bool update (const value &env)
	{
		const value &list = env["Domain:WebDAV"]["WebDAV:User"];
		string owner = env["Domain:WebDAV"]("owner");
		file f;
		
		f.openwrite ("webdav.passwd");
		foreach (user, list)
		{
			f.writeln ("%s:%s" %format (user["metaid"],user["password"]));
		}
		f.close ();
		
		string dpath = "www/%s/conf" %format (id);
		if (! authd.installUserFile ("webdav.passwd", dpath, owner))
		{
			error (CoreModule::E_OTHER, "Error installing webdav.passwd");
		}
	}
	
	bool create (const value &env)
	{
		if (env["OpenCORE:Session"]["classid"] == "WebDAV:User")
		{
			return update (env);
		}
		string tmpl = fs.load ("/etc/webdav/template.conf");
		string owner = env["Domain:WebDAV"]("owner");
		value pw = core.userdb.getpwnam (owner);
		if (! pw)
		{
			error (CoreModule::E_OTHER, "Unknown user");
			return false;
		}
		
		value gr = core.userdb.getgrgid (pw["gid"].uval());
		if (! gr)
		{
			error (CoreModule::E_OTHER, "Unknwon user group");
			return false;
		}
		
		string group = gr["groupname"];
		string docroot = "%s/www/%s" %format (pw["home"],id);
		
		value conf = loadconf();
		int port = findport (conf);
		conf[id] = port;
		if (! saveconf (conf)) return false;
		
		value senv = $("user",owner)->
					 $("group",group)->
					 $("docroot",docroot)->
					 $("vhost",id)->
					 $("port",port);
					 
		tmpl = strutil::valueparse (tmpl, senv);
		fs.save ("httpd.conf", tmpl);
		
		if (! createdirs(id,owner))
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
		if (! authd.reloadService ("webdav"))
		{
			error (CoreModule::E_OTHER, "Could not restart webdav service");
			return false;
		}
		
		return true;
	}
	
	bool remove (const value &env)
	{
		if (env["OpenCORE:Session"]["classid"] == "WebDAV:User")
		{
			return update (env);
		}
		
		value conf = loadconf();
		conf[id] = 0;
		if (! saveconf (conf)) return false;
		
		if (! authd.reloadService ("webdav"))
		{
			error (CoreModule::E_OTHER, "Could not restart webdav service");
			return false;
		}
		
		authd.deleteDir ("/var/webdav/%s" %format (id));
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

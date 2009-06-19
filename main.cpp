#include <grace-coreapi/module.h>
#include <grace/filesystem.h>
#include <grace/system.h>

class WebDAV : public CoreClass
{
public:
	WebDAV (void) : CoreClass ("Domain:WebDAV")
	{
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
		
		while (portfound = true)
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
		}
		authd.makeUserDir (user, "0700", ".webdav");
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
		
		if (! authd.installUserFile ("webdav.passwd",".webdav", owner))
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
		string docroot = pw["home"];
		
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

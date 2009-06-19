#ifndef _webdav_H
#define _webdav_H 1
#include <grace/application.h>
#include <grace/configdb.h>

//  -------------------------------------------------------------------------
/// Implementation template for application config.
//  -------------------------------------------------------------------------
typedef configdb<class webdavApp> appconfig;

//  -------------------------------------------------------------------------
/// Main application class.
//  -------------------------------------------------------------------------
class webdavApp : public application
{
public:
		 		 webdavApp (void) :
					application ("com.openpanel.modules.webdav"),
					conf (this)
				 {
				 	opt = $("-h", $("long", "--help"));
				 }
				~webdavApp (void)
				 {
				 }
	
	int			 main (void);

protected:
	appconfig	 conf;
};

#endif


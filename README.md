Ansible for windows. 

Demo for running AWX project for windows hosts. 

I have a awx running in a k3 cluster which is set to manage windows machines. 

I will also upload the snapshots of AWX configurations


Recommended directory structure 

hosts                     # inventory file

group_vars/
   group1.yml             # here we assign variables to particular groups
   group2.yml
host_vars/
   hostname1.yml          # here we assign variables to particular systems
   hostname2.yml

library/                  # if any custom modules, put them here (optional)
module_utils/             # if any custom module_utils to support modules, put them here (optional)
filter_plugins/           # if any custom filter plugins, put them here (optional)

site.yml                  # master playbook
webservers.yml            # playbook for webservers role
dbservers.yml             # playbook for dbservers role
fooapp.yml                # playbook for foo app

roles/
    common/               # this hierarchy represents defaults for a "role"
        tasks/            #
            main.yml      #  <-- tasks file can include smaller files if warranted
        handlers/         #
            main.yml      #  <-- handlers file
        templates/        #  <-- files for use with the template resource
            ntp.conf.j2   #  <------- templates end in .j2
        files/            #
            bar.txt       #  <-- files for use with the copy resource
            foo.sh        #  <-- script files for use with the script resource
        vars/             #
            main.yml      #  <-- variables associated with this role
        defaults/         #
            main.yml      #  <-- default lower priority variables for this role
        meta/             #
            main.yml      #  <-- role dependencies
        library/          # roles can also include custom modules
        module_utils/     # roles can also include custom module_utils
        lookup_plugins/   # or other types of plugins, like lookup in this case

    webservers/           # same kind of structure as "common" was above, done for the webservers role
    dbservers/            # ""
    fooapp/               # ""

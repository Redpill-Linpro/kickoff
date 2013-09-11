$packages = [ 'nginx', 'uwsgi', 'uwsgi-plugin-python', 'vim', 
              'uwsgi-plugin-http', 'curl', 'python-dulwich',
              'mongodb', 'python-pymongo', 'language-pack-nb-base',
              'language-pack-nb', 'language-pack-kde-nb-base',
              'git' ]
package {
    $packages: ensure => installed;
}

File {
    require => Package[$packages],
}

file { 
    '/etc/motd':
        content => "\nThis is the kickoff build environment\n\n";
    '/etc/nginx/sites-enabled/default': 
        notify  => Service['nginx'],
        source  => '/vagrant/puppet/files/nginx/default';
    '/etc/uwsgi/apps-enabled/kickoff.yaml': 
        notify  => Service['uwsgi'],
        source  => '/vagrant/puppet/files/uwsgi/kickoff.yaml';
    '/var/lib/kickoff':
        ensure  => directory,
        owner   => 'www-data',
        group   => 'www-data',
        mode    => 700;
    '/srv/www':
        ensure  => directory,
        notify  => Service['nginx'];
    '/srv/www/kickoff':
        ensure  => link,
        require => File['/srv/www'],
        notify  => Service['nginx'],
        target  => '/vagrant/kickoff';
}

Service {
    ensure     => true,
    require    => Package[$packages],
    hasrestart => true,
    enable     => true,
    notify     => Notify[$fqdn],
}

service {
    'nginx': ;
    'mongodb': ;
    'uwsgi': 
        require => [File['/etc/uwsgi/apps-enabled/kickoff.yaml'],
                    File['/srv/www/kickoff']];
}

notify {
    $fqdn:
        message => "The kickoff web application is available at http://${ipaddress_eth1}/";
}

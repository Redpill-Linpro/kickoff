$packages = [ 'nginx', 'uwsgi', 'uwsgi-plugin-python', 'vim', 
              'uwsgi-plugin-http' ]
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
}

service {
    'nginx': ;
    'uwsgi': 
        require => [File['/etc/uwsgi/apps-enabled/kickoff.yaml'],
                    File['/srv/www/kickoff']];
}

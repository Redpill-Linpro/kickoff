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
        source  => '/vagrant/files/nginx/default';
    '/etc/uwsgi/apps-enabled/kickoff.yaml': 
        notify  => Service['uwsgi'],
        source  => '/vagrant/files/uwsgi/kickoff.yaml';
    '/srv/www':
        notify  => Service['nginx'],
        ensure  => directory;
    '/srv/www/kickoff':
        require => File['/srv/www'],
        notify  => Service['nginx'],
        ensure  => link,
        target  => '/vagrant/kickoff';
}

Service {
    require    => Package[$packages],
    hasrestart => true,
    enable     => true,
    ensure     => true,
}

service {
    'nginx': ;
    'uwsgi': 
        require => File['/etc/uwsgi/apps-enabled/kickoff.yaml'];
}

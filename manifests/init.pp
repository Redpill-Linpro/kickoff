$packages = [ 'nginx', 'uwsgi', 'uwsgi-plugin-python', 'vim' ]
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

user {
    "kickoff": 
        require    => Group["kickoff"],
        managehome => false,
        ensure     => present,
        shell      => "/bin/false",
        gid        => "kickoff";
}

group {
    "kickoff":
        ensure => present;
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
        require => User["kickoff"];
}

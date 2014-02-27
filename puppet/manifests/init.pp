$packages = [ 'nginx', 'uwsgi', 'uwsgi-plugin-python', 'vim', 
              'uwsgi-plugin-http', 'curl', 'python-dulwich',
              'mongodb', 'python-pymongo', 'language-pack-nb-base',
              'language-pack-nb', 'language-pack-kde-nb-base',
              'git', 'rlwrap' ]
package {
    $packages: 
        ensure  => 'installed',
        require => Exec['apt-get update'];
}

File {
    require => Package[$packages],
}

file { 
    '/var/log/kickoff_slaves':
        ensure => 'directory',
        owner  => 'root',
        group  => 'root';
    '/var/log/kickoff':
        ensure => 'directory',
        owner  => 'www-data',
        group  => 'www-data';
    '/srv/kickoff':
        ensure => 'directory',
        owner  => 'www-data',
        group  => 'www-data';
    '/etc/motd':
        content => "\nThis is the kickoff build environment\n\n";
    '/etc/nginx/sites-enabled/default': 
        notify  => Service['nginx'],
        source  => '/vagrant/puppet/files/nginx/default';
    '/etc/uwsgi/apps-enabled/kickoff.yaml': 
        notify  => Service['uwsgi'],
        source  => '/vagrant/puppet/files/uwsgi/kickoff.yaml';
    '/var/lib/kickoff':
        ensure  => 'directory',
        owner   => 'www-data',
        group   => 'www-data',
        mode    => 700;
    '/srv/www':
        ensure  => 'directory',
        notify  => Service['nginx'];
    '/srv/www/kickoff':
        ensure  => 'link',
        require => File['/srv/www'],
        notify  => Service['nginx'],
        target  => '/vagrant/kickoff';
    '/etc/logrotate.d/kickoff':
        mode    => '0444',
        owner   => 'root',
        group   => 'root',
        content => "/var/log/kickoff/*log {\n daily\n rotate 90\n copytruncate\n delaycompress\n}";
}

Service {
    ensure     => true,
    require    => Package[$packages],
    hasrestart => true,
    enable     => true,
}

service {
    'nginx': ;
    'mongodb': ;
    'uwsgi': 
        require => [Package[$packages],
                    File['/etc/uwsgi/apps-enabled/kickoff.yaml'],
                    File['/srv/www/kickoff']];
}

exec {
    "apt-get update":
        command     => 'apt-get update',
        path        => '/sbin:/bin:/usr/bin:/usr/sbin',
        user        => 'root';
}

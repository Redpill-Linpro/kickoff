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
}

#yumrepo {
#    'epel':
#        baseurl => 'http://repo.i.bitbit.net/rhel6/6Server-$basearch/RPMS.epel',
#        descr   => 'Extra Packages for Enterprise Linux 6',
#        gpgkey  => 'file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6',
#        require => File['/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6'];
#}

Service {
    require    => Package[$packages],
    hasrestart => true,
    enable     => true,
    ensure     => true,
}

service {
    'nginx': ;
    'uwsgi': ;
}

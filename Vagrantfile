# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "kickoff"
  config.vm.box_url = 'http://repo.i.bitbit.net/vagrant/rl-precise.box'
  #config.vm.customize ["modifyvm", :id, "--memory", 1024]
  #config.vm.network :hostonly, "192.168.33.10"
  config.vm.provision :puppet do |puppet|
    puppet.manifests_path = "manifests"
    puppet.manifest_file  = "init.pp"
  end
end

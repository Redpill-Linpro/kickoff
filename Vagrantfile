# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "kickoff"
  config.vm.box_url = 'http://repo.i.bitbit.net/vagrant/rl-precise.box'
  config.vm.network :private_network, ip: "192.168.50.4"
  #config.vm.network :public_network
  config.vm.provision :puppet do |puppet|
    puppet.manifests_path = "puppet/manifests"
    puppet.manifest_file  = "init.pp"
  end
end

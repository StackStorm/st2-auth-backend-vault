vault_addr    = ENV['VAULT_ADDR'] ? ENV['VAULT_ADDR'] : 'http://127.0.0.1:8200'
vault_token   = ENV['VAULT_TOKEN'] ? ENV['VAULT_TOKEN'] : 'st2token'


Vagrant.configure("2") do |config|
  config.vm.provider "docker" do |d|
    d.image = "vault"
    # https://hub.docker.com/_/vault/
    d.create_args = ["--cap-add=IPC_LOCK"]
    d.env = {"VAULT_DEV_ROOT_TOKEN_ID" => vault_token,
             "VAULT_ADDR" => vault_addr}
    d.ports = ["127.0.0.1:8200:8200"]
  end
  
  config.vm.provision "docker" do |d|
    d.run "vault",
          cmd: "vault"
  end
end

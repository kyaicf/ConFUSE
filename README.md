
# ConFUSE

ConFUSE: A System to Achieve Fast Container Startup

# Get Started

### 1. Clone the repository
```console
# git clone https://github.com/kyaicf/ConFUSE.git
# cd ConFUSE
```

### 2. Install the 6.9.1 Linux kernel 
```console
# dnf -y install gcc make ncurses-devel flex bison openssl openssl-devel elfutils-libelf-devel binutils binutils-devel lz4

# cd linux
# cp -v /boot/config-$(uname -r) .config
# make menuconfig          # --> CONFIG_FUSE_FS=m CONFIG_FUSE_PASSTHROUGH=y

# make -j$(nproc)
# make modules_install
# make headers_install
# make install

--> Update grub to load v6.9.1 and reboot
```

### 3. Install containerd
```console
# wget https://github.com/containerd/containerd/releases/download/v1.7.16/cri-containerd-cni-1.7.16-linux-amd64.tar.gz
# tar -xaf cri-containerd-cni-1.7.16-linux-arm64.tar.gz -C /
```

### 4. Compile and install stargz-snapshotter
```console
# cd stargz-snapshotter
# make
# make install
# cp -r ./script/config/etc /

# systemctl start containerd.service
# systemctl start stargz-snapshotter.service
```

### 5. Convert and push image
Take redis image for example
```console
# ctr-remote image pull docker.io/library/redis:6.2.6
# ctr-remote images convert --oci --estargz docker.io/library/redis:6.2.6 registry2:5000/redis:6.2.6-esgz-phash
# ctr-remote image push --plain-http registry2:5000/redis:6.2.6-esgz-phash
# ctr-remote image rm --sync registry2:5000/redis:6.2.6-esgz-phash
```

### 6. Run container
```console
# ctr-remote image rpull --plain-http --snapshotter=stargz registry2:5000/redis:6.2.6-esgz-phash
# ctr-remote run -d --snapshotter=stargz registry2:5000/redis:6.2.6-esgz-phash redis
```


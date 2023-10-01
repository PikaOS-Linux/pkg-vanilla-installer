# Clone Upstream
mkdir -p ./vanilla-installer
rsync -av --progress ./* ./vanilla-installer --exclude ./vanilla-installer
cd ./vanilla-installer

# Get build deps
apt-get build-dep ./ -y

# Build package
dpkg-buildpackage --no-sign

# Move the debs to output
cd ../
mkdir -p ./output
mv ./*.deb ./output/
Local test:
1. Make nfsd export

Can see what server is currently exporting with
`exportfs -s`

2. Make a local mount point 
`mkdir /mnt/foo`

3. Mount 
if needed: systemctl restart nfs-server
`mount -t nfs 127.0.0.1:/export/foo /mnt/foo`

4. Run tests scripts
./send-nfs-ops.sh


References:
https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/managing_file_systems/mounting-nfs-shares_managing-file-systems
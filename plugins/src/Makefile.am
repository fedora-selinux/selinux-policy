# Clear out cruft from any previous install.  There is a lot of churn
# at the moment and plugin's are often removed from previous
# versions. Also, we don't support plugin's which don't originate from us
# so there should be lttle fear of nuking something which should persist.
install-data-local:
	rm -f $(DESTDIR)$(plugindir)/*.py

PLUGIN_FILES =				\
	allow_anon_write.py		\
	allow_execheap.py		\
	allow_execmod.py		\
	allow_execstack.py		\
	allow_ftpd_use_cifs.py		\
	allow_ftpd_use_nfs.py		\
	automount_exec_config.py	\
	bind_ports.py			\
	catchall_boolean.py		\
	catchall_labels.py		\
	catchall.py			\
	connect_ports.py		\
	cvs_data.py			\
	device.py			\
	disable_ipv6.py			\
	file.py				\
	filesystem_associate.py		\
	httpd_can_sendmail.py		\
	httpd_write_content.py		\
	__init__.py			\
	kernel_modules.py		\
	leaks.py			\
	mmap_zero.py			\
	mounton.py			\
	public_content.py		\
	qemu_blk_image.py		\
	qemu_file_image.py		\
	restorecon.py			\
	rsync_data.py			\
	samba_share.py			\
	selinuxpolicy.py		\
	setenforce.py			\
	sshd_root.py			\
	swapfile.py			\
	sys_module.py			\
	sys_resource.py			\
	vbetool.py			\
	wine.py				\
	xen_image.py			\
	$(NULL)
plugin_PYTHON = $(PLUGIN_FILES)


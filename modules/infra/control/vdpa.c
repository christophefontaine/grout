// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include "log.h"
#include "netlink.h"
#include "vdpa.h"

#include <gr_errno.h>
#include <gr_string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

LOG_TYPE("vdpa");

#define SYS_VDPA_DEVICES "/sys/bus/vdpa/devices"
#define SYS_VDPA_DRIVERS "/sys/bus/vdpa/drivers"

int vdpa_dev_add(const char *name) {
	// The vDPA lifecycle (generic netlink) is driven from the centralized
	// netlink module, so all libmnl usage lives in one place. Failures are
	// already logged there, so just propagate the error code.
	int ret = netlink_vdpa_dev_add(name);
	if (ret < 0)
		return ret;
	LOG(INFO, "vdpa device %s added", name);
	return 0;
}

int vdpa_dev_del(const char *name) {
	int ret = netlink_vdpa_dev_del(name);
	if (ret < 0)
		return ret;
	LOG(INFO, "vdpa device %s removed", name);
	return 0;
}

// Write a NUL terminated string to a sysfs attribute file.
static int sysfs_write(const char *path, const char *value) {
	ssize_t len = strlen(value);
	int fd, ret = 0;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (write(fd, value, len) != len)
		ret = -errno;
	close(fd);

	return ret;
}

// Return the driver currently bound to the vDPA device, or "" if none.
void vdpa_current_driver(const char *name, char *buf, size_t size) {
	char target[PATH_MAX];
	const char *driver;
	char path[PATH_MAX];
	ssize_t n;

	if (size == 0)
		return;
	buf[0] = '\0';
	snprintf(path, sizeof(path), SYS_VDPA_DEVICES "/%s/driver", name);
	// The "driver" symlink points at .../bus/vdpa/drivers/<driver>. Read the
	// full target into a large buffer first, then copy only the basename, so a
	// small caller buffer does not truncate the path before the driver name.
	n = readlink(path, target, sizeof(target) - 1);
	if (n < 0)
		return;
	target[n] = '\0';
	driver = strrchr(target, '/');
	driver = driver != NULL ? driver + 1 : target;
	gr_strcpy(buf, size, driver);
}

int vdpa_bind_driver(const char *name, const char *driver) {
	char current[NAME_MAX + 1];
	char path[PATH_MAX];
	int ret;

	vdpa_current_driver(name, current, sizeof(current));
	if (strcmp(current, driver) == 0)
		return 0; // already bound to the requested driver

	// Unbind from the auto-probed driver, if any (e.g. virtio_vdpa binds by
	// default when its module is loaded).
	if (current[0] != '\0') {
		snprintf(path, sizeof(path), SYS_VDPA_DRIVERS "/%s/unbind", current);
		if ((ret = sysfs_write(path, name)) < 0)
			return errno_log(-ret, "vdpa unbind");
	}

	// Pin the device to the requested driver and trigger the bind.
	snprintf(path, sizeof(path), SYS_VDPA_DEVICES "/%s/driver_override", name);
	if ((ret = sysfs_write(path, driver)) < 0)
		return errno_log(-ret, "vdpa driver_override");

	snprintf(path, sizeof(path), SYS_VDPA_DRIVERS "/%s/bind", driver);
	if ((ret = sysfs_write(path, name)) < 0) {
		if (ret == -ENOENT)
			LOG(ERR, "vdpa driver %s not available (is its module loaded?)", driver);
		return errno_log(-ret, "vdpa bind");
	}

	LOG(INFO, "vdpa device %s bound to %s", name, driver);
	return 0;
}

// Find the kernel netdev created by virtio_vdpa for a vDPA device.
// Path layout: /sys/bus/vdpa/devices/<name>/virtio<N>/net/<netdev>
static int vdpa_netdev_name(const char *name, char *buf, size_t size) {
	char path[PATH_MAX];
	struct dirent *e;
	int ret = -ENOENT;
	DIR *dev_dir;

	snprintf(path, sizeof(path), SYS_VDPA_DEVICES "/%s", name);
	dev_dir = opendir(path);
	if (dev_dir == NULL)
		return -errno;

	while ((e = readdir(dev_dir)) != NULL) {
		char net_path[PATH_MAX];
		struct dirent *ne;
		DIR *net_dir;

		if (strncmp(e->d_name, "virtio", 6) != 0)
			continue;

		snprintf(net_path, sizeof(net_path), "%s/%s/net", path, e->d_name);
		net_dir = opendir(net_path);
		if (net_dir == NULL)
			continue;

		while ((ne = readdir(net_dir)) != NULL) {
			if (ne->d_name[0] == '.')
				continue;
			if (gr_strcpy(buf, size, ne->d_name) < 0)
				continue;
			ret = 0;
			break;
		}
		closedir(net_dir);
		break;
	}
	closedir(dev_dir);

	return ret;
}

uint32_t vdpa_netdev_ifindex(const char *name) {
	char cur[IF_NAMESIZE];

	if (vdpa_netdev_name(name, cur, sizeof(cur)) < 0)
		return 0;
	return if_nametoindex(cur);
}

// Whether two open netns fds refer to the same network namespace.
static bool same_netns(int a, int b) {
	struct stat sa, sb;

	if (fstat(a, &sa) < 0 || fstat(b, &sb) < 0)
		return false;
	return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

int vdpa_netns_enter(const char *netns_path, int *prev_fd) {
	int target, prev, ret;

	*prev_fd = -1;

	// No vdpa netns configured: grout's current netns already has vdpa
	// access (bare metal or --net=host). Nothing to do.
	if (netns_path == NULL)
		return 0;

	target = open(netns_path, O_RDONLY | O_CLOEXEC);
	if (target < 0)
		return errno_log(errno, netns_path);

	prev = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (prev < 0) {
		ret = errno_log(errno, "/proc/self/ns/net");
		close(target);
		return ret;
	}

	// Already in the vdpa netns (e.g. the reference points at our own netns):
	// no setns needed and nothing to restore.
	if (same_netns(target, prev)) {
		close(target);
		close(prev);
		return 0;
	}

	if (setns(target, CLONE_NEWNET) < 0) {
		ret = errno_log(errno, "setns");
		close(target);
		close(prev);
		return ret;
	}
	close(target);
	*prev_fd = prev;
	return 0;
}

void vdpa_netns_leave(int prev_fd) {
	if (prev_fd < 0)
		return;
	if (setns(prev_fd, CLONE_NEWNET) < 0)
		LOG(ERR, "setns back: %s", strerror(errno));
	close(prev_fd);
}

int vdpa_rename_netdev(const char *name, const char *new_name) {
	char cur[IF_NAMESIZE];
	uint32_t ifindex;
	int ret;

	if ((ret = vdpa_netdev_name(name, cur, sizeof(cur))) < 0)
		return errno_log(-ret, "vdpa netdev lookup");
	if (strcmp(cur, new_name) == 0)
		return 0;

	ifindex = if_nametoindex(cur);
	if (ifindex == 0)
		return errno_log(errno, "if_nametoindex");

	// The kernel only allows renaming an administratively down interface.
	// Reuse the centralized netlink helpers instead of raw ioctls.
	if (netlink_link_set_admin_state(ifindex, false, false) < 0)
		return errno_log(errno, "netlink_link_set_admin_state");
	if (netlink_link_set_name(ifindex, new_name) < 0)
		return errno_log(errno, "netlink_link_set_name");

	LOG(INFO, "vdpa netdev %s renamed to %s", cur, new_name);
	return 0;
}

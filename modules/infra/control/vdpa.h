// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#pragma once

#include <stddef.h>
#include <stdint.h>

// Helpers to drive the kernel vDPA subsystem for VDUSE ports.
//
// Once a VDUSE device has been created in userspace (by the DPDK vhost library
// when a net_vhost port uses iface=/dev/vduse/<name>), the matching vDPA device
// must be instantiated on the vdpa bus and bound to a driver:
//   virtio_vdpa -> exposes a virtio-net netdev in the host kernel
//   vhost_vdpa  -> exposes /dev/vhost-vdpa-* for a VM
//
// These operations are the equivalent of:
//   vdpa dev add name <name> mgmtdev vduse
//   vdpa dev del name <name>
// plus binding the resulting device to the requested vdpa bus driver via sysfs.

#define VDPA_DRIVER_VIRTIO "virtio_vdpa"
#define VDPA_DRIVER_VHOST "vhost_vdpa"

// Instantiate a vDPA device from the "vduse" management device.
int vdpa_dev_add(const char *name);

// Remove a vDPA device previously created with vdpa_dev_add().
int vdpa_dev_del(const char *name);

// Bind a vDPA device to the given vdpa bus driver (VDPA_DRIVER_*).
// Rebinds if the device is currently bound to another driver.
int vdpa_bind_driver(const char *name, const char *driver);

// Return the vdpa bus driver currently bound to the device (VDPA_DRIVER_*),
// or "" if none. Used to report the attach mode of a VDUSE port.
void vdpa_current_driver(const char *name, char *buf, size_t size);

// Rename the host kernel netdev created by virtio_vdpa for the given vDPA
// device (host mode only). The netdev otherwise gets a kernel default name
// (e.g. "eth0"); renaming it to a predictable name (e.g. "dp-<iface>") keeps
// it distinct from the interface's control plane TAP.
int vdpa_rename_netdev(const char *name, const char *new_name);

// Return the ifindex of the host kernel netdev created by virtio_vdpa for the
// given vDPA device, resolved in the caller's current netns, or 0 if not found.
uint32_t vdpa_netdev_ifindex(const char *name);

// Enter the network namespace where the kernel vdpa generic-netlink family
// lives (its initial netns) so vdpa operations succeed when grout runs isolated
// in its own netns. netns_path is a bind-mounted reference to that netns
// (GROUT_VDPA_NETNS); NULL means grout's current netns already has vdpa access,
// in which case this is a no-op.
//
// On success *prev_fd is set to an open fd for the caller's previous netns (to
// pass to vdpa_netns_leave), or -1 when no namespace switch happened. Returns a
// negative errno on failure.
int vdpa_netns_enter(const char *netns_path, int *prev_fd);

// Return to the netns saved by vdpa_netns_enter() and close prev_fd. A negative
// prev_fd (no switch happened) is a no-op.
void vdpa_netns_leave(int prev_fd);

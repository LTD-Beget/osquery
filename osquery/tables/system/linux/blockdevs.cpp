#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>
#include <map>

#include <boost/lexical_cast.hpp>

#include <libudev.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

class BlockDevice {
	public:
		std::string name;
		std::string parent;
		std::map<std::string, std::string> attr;

		BlockDevice(struct udev_device *dev) {
			struct udev_device *parent;
			const char *size;

			parent = udev_device_get_parent_with_subsystem_devtype(dev, "block", NULL);

			this->name = std::string(udev_device_get_devnode(dev));
			if (parent) {
				this->parent = std::string(udev_device_get_devnode(parent));
			}
			size = udev_device_get_sysattr_value(dev, "size");
			if (size) {
				this->attr.insert(std::pair<std::string,std::string>(std::string("size"), std::string(size)));
			}
		}
};

std::vector<BlockDevice> getBlockDevices() {
	std::vector<BlockDevice> results;

	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev, *parent;

	if ((udev = udev_new())) {
		enumerate = udev_enumerate_new(udev);
		udev_enumerate_add_match_subsystem(enumerate, "block");
		udev_enumerate_scan_devices(enumerate);
		devices = udev_enumerate_get_list_entry(enumerate);
		udev_list_entry_foreach(dev_list_entry, devices) {
			const char *path;

			path = udev_list_entry_get_name(dev_list_entry);
			dev = udev_device_new_from_syspath(udev, path);

			BlockDevice bd = BlockDevice(dev);
			results.push_back(bd);

			udev_device_unref(dev);
		}
	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	return results;

}

QueryData genBlockDevs() {
	QueryData results;
	std::vector<BlockDevice> devices = getBlockDevices();

	for (auto &dev: devices) {
		Row r;

		r["name"] 	= dev.name;
		r["parent"] = dev.parent;
		r["size"] = dev.attr["size"];
		results.push_back(r);
	}

	return results;
}
}
}

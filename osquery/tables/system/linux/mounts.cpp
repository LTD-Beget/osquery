#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

#include <stdio.h>
#include <mntent.h>

namespace osquery {
namespace tables {
QueryData genMounts() {
	QueryData results;
	FILE *mounts;
	struct mntent *ent;

	if (mounts = setmntent("/proc/mounts", "r")) {
		while (ent = getmntent(mounts)) {
			Row r;

			r["fsname"] = std::string(ent->mnt_fsname);
			r["dir"] = std::string(ent->mnt_dir);
			r["type"] = std::string(ent->mnt_type);
			r["opts"] = std::string(ent->mnt_opts);
			r["freq"] = boost::lexical_cast<std::string>(ent->mnt_freq);
			r["passno"] = boost::lexical_cast<std::string>(ent->mnt_passno);

			results.push_back(r);
		}
		endmntent(mounts);
	}

	return results;
}
}
}

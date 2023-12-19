import { PackageManagerType } from "@soos-io/api-client";

export const removeDuplicates = <T>(list: Array<T>): Array<T> => [...new Set(list)];

export const getAvailablePackageManagers = (): PackageManagerType[] => {
  return Object.keys(PackageManagerType)
    .filter(
      (key) =>
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Unknown &&
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Alpine &&
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Debian &&
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Docker &&
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Fedora &&
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Swift &&
        PackageManagerType[key as keyof typeof PackageManagerType] !== PackageManagerType.Wolfi,
    )
    .map((key) => PackageManagerType[key as keyof typeof PackageManagerType]);
};

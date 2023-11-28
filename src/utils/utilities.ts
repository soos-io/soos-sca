export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return "0 Bytes";

  const kilobyte = 1024;
  const fractionalDigits = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];

  const exponentialValue = Math.floor(Math.log(bytes) / Math.log(kilobyte));
  const count = Number.parseFloat(
    (bytes / Math.pow(kilobyte, exponentialValue)).toFixed(fractionalDigits)
  );
  const unit = sizes[exponentialValue];
  return `${count} ${unit}`;
}

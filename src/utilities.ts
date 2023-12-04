export const getDirectoriesToExclude = (excludedDirectoriesInput: Array<string>): Array<string> => {
  const cleansedInput = excludedDirectoriesInput.map((pattern) => pattern.trim());
  return removeDuplicates(cleansedInput);
};

export const removeDuplicates = <T>(list: Array<T>): Array<T> => [...new Set(list)];

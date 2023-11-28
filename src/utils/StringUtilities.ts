const StringUtilities = {
  pluralizeWord: (
    count: number | null | undefined,
    singular: string,
    plural = `${singular}s`
  ): string => {
    return count === 1 ? singular : plural;
  },
  pluralizeTemplate: (count: number | null, singular: string, plural = `${singular}s`): string => {
    const word = StringUtilities.pluralizeWord(count, singular, plural);
    return `${count ?? 0} ${word}`;
  },
  /**
   * @see https://stackoverflow.com/a/7225474
   */
  fromCamelToTitleCase: (str: string): string => {
    const [firstCharacter, ...rest] = str.replace(/([A-Z]+)*([A-Z][a-z])/g, "$1 $2").trim();
    return `${firstCharacter.toLocaleUpperCase()}${rest.join("")}`;
  },
  areEqual: (
    a: string,
    b: string,
    options?: { locales?: Array<string> } & Intl.CollatorOptions
  ) => {
    return a.localeCompare(b, options?.locales, options) === 0;
  },
};

export default StringUtilities;

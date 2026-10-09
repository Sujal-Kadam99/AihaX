const packageConfig = require('./package.json').build;
const releaseBuild = process.env.AIHAX_RELEASE_BUILD === '1';
const publisherName = process.env.AIHAX_UPDATE_PUBLISHER?.trim();
const updateUrl = process.env.AIHAX_UPDATE_URL?.trim();
const { sign: _disabledSigning, ...windowsOptions } = packageConfig.win;

if (releaseBuild) {
  if (!publisherName || !process.env.CSC_LINK) {
    throw new Error(
      'Release builds require AIHAX_UPDATE_PUBLISHER and CSC_LINK signing credentials.'
    );
  }

  let parsedUpdateUrl;
  try {
    parsedUpdateUrl = new URL(updateUrl);
  } catch {
    throw new Error('Release builds require a valid AIHAX_UPDATE_URL.');
  }
  if (parsedUpdateUrl.protocol !== 'https:' || parsedUpdateUrl.username || parsedUpdateUrl.password) {
    throw new Error('AIHAX_UPDATE_URL must be a credential-free HTTPS URL.');
  }
}

module.exports = {
  ...packageConfig,
  win: {
    ...windowsOptions,
    ...(releaseBuild
      ? { publisherName: [publisherName] }
      : { sign: false, signAndEditExecutable: false }),
  },
  ...(releaseBuild
    ? { publish: [{ provider: 'generic', url: updateUrl }] }
    : {}),
};

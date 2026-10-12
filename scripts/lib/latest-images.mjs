import { join } from "node:path";
import { names } from "../../shared/config.mjs";
import { buildCoreImage, publishLatestImage } from "./image-build.mjs";
import { buildDrowsyDragon } from "./drowsy-dragon.mjs";
import { buildNginxProxy } from "./nginx-proxy.mjs";

export async function publishLatestImages(config, output, options = {}) {
  const resourceNames = names(config);
  const images = {};
  for (const [component, repository] of [
    ["dojo", resourceNames.dojo],
    ["portal", resourceNames.portal],
    ["secretBootstrap", "secret-bootstrap"],
  ]) {
    images[component] = await buildCoreImage(
      component,
      `${resourceNames.registry}.azurecr.io/${repository}:latest`,
      join(output, component),
      { ...options, latest: true, repository, source: config.source },
    );
  }
  if (config.drowsyDragonEnabled) {
    images.drowsyDragon = await buildDrowsyDragon(
      `${resourceNames.registry}.azurecr.io/${resourceNames.drowsyDragon}:latest`,
      join(output, "drowsyDragon"),
      { ...options, latest: true, repository: resourceNames.drowsyDragon },
    );
  }
  if (config.nginxProxyEnabled) {
    images.nginxProxy = await buildNginxProxy(
      `${resourceNames.registry}.azurecr.io/${resourceNames.nginxProxy}:latest`,
      join(output, "nginxProxy"),
      config.nginxProxyMode,
      { ...options, latest: true, repository: resourceNames.nginxProxy },
    );
  }
  for (const [component, entry] of Object.entries(images))
    images[component] = await publishLatestImage(config, entry, join(output, component), options);
  return images;
}

export function mergePricing(current, desired) {
  const properties = structuredClone(current.properties || {});
  for (const key of [
    "freeTrialRemainingTime",
    "enablementTime",
    "resourcesCoverageStatus",
    "deprecated",
    "replacedBy",
    "inherited",
    "inheritedFrom",
  ])
    delete properties[key];
  properties.pricingTier = desired.pricingTier;
  if (desired.subPlan && !properties.subPlan)
    properties.subPlan = desired.subPlan;
  const extensions = new Map(
    (properties.extensions || []).map((extension) => [
      extension.name,
      extension,
    ]),
  );
  for (const extension of desired.extensions || [])
    extensions.set(extension.name, {
      ...extensions.get(extension.name),
      ...extension,
    });
  if (extensions.size)
    properties.extensions = [...extensions.values()].map(
      ({ operationStatus: _operationStatus, ...extension }) => extension,
    );
  return { properties };
}

export function pricingMatches(current, desired) {
  return (
    current.properties?.pricingTier === desired.pricingTier &&
    (!desired.subPlan || current.properties?.subPlan === desired.subPlan) &&
    (desired.extensions || []).every((extension) =>
      current.properties?.extensions?.some(
        (actual) =>
          actual.name === extension.name &&
          actual.isEnabled === extension.isEnabled &&
          (!actual.operationStatus?.code ||
            actual.operationStatus.code === "Succeeded"),
      ),
    )
  );
}

export async function reconcileProtection(
  client,
  desired,
  { apply = false } = {},
) {
  const decisions = [];
  for (const [name, settings] of Object.entries(desired)) {
    const path = `${client.scope}/providers/Microsoft.Security/pricings/${name}?api-version=2024-01-01`;
    const before = await client.request(path);
    if (
      settings.subPlan &&
      before.properties?.pricingTier === "Standard" &&
      before.properties.subPlan &&
      before.properties.subPlan !== settings.subPlan
    ) {
      throw new Error(
        `Existing ${name} subplan differs; review it explicitly before changing billing`,
      );
    }
    const matches = pricingMatches(before, settings);
    let observed = before;
    if (!matches && apply) {
      await client.request(path, {
        method: "PUT",
        body: mergePricing(before, settings),
      });
      observed = await client.request(path);
      if (!pricingMatches(observed, settings))
        throw new Error(`${name} readback did not match requested protection`);
    }
    decisions.push({
      name,
      state: matches ? "found" : apply ? "updated" : "requires-consent",
      desired: settings,
      observed: observed.properties,
    });
  }
  return decisions;
}

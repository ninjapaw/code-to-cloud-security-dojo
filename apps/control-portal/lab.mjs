import { randomUUID } from "node:crypto";
import { isLabHostname } from "../../shared/config.mjs";

export const tests = [
  {
    id: "health",
    title: "Dojo health",
    kind: "Connectivity",
    path: "/WebGoat/actuator/health",
    expected: "HTTP response only. No alert expected.",
  },
  {
    id: "defender-validation",
    title: "Defender validation request",
    kind: "Documented validation",
    path: "/This_Will_Generate_ASC_Alert",
    expected:
      "Microsoft-documented App Service test. New sites may need 24 hours to register; alerts may take 2-4 hours. Detection is not guaranteed.",
  },
  {
    id: "sqli-probe",
    title: "SQL-shaped input probe",
    kind: "Bounded attack-shaped request",
    path: "/WebGoat/login?username=%27%20OR%20%271%27%3D%271",
    expected:
      "One fixed GET input probe, not a successful SQL exploit or an authenticated WebGoat lesson.",
  },
];

export async function runLabTest({ id, config, store, fetcher = fetch }) {
  const test = tests.find((item) => item.id === id);
  if (!test) throw Object.assign(new Error("Unknown test"), { status: 400 });
  if (!isLabHostname(config.dojoHost, config.dojoName))
    throw new Error("Invalid fixed training target");
  return store.withLock(async () => {
    const startedAt = new Date().toISOString();
    const run = {
      id: randomUUID(),
      testId: test.id,
      startedAt,
      targetResourceId: config.dojoResourceId,
      imageDigest: config.dojoDigest,
      state: "started",
      expected: test.expected,
      attribution: "No detection or prevention claim",
    };
    const key = `runs/${startedAt}-${run.id}.json`;
    await store.put(key, run);
    try {
      const response = await fetcher(
        `https://${config.dojoHost}${test.path}`,
        {
          method: "GET",
          redirect: "manual",
          signal: AbortSignal.timeout(10000),
          headers: {
            "User-Agent": "CodeToCloud-AuthorizedTraining/1.0",
            "X-Dojo-Run-Id": run.id,
          },
        },
      );
      run.httpStatus = response.status;
      run.state =
        response.status >= 300 && response.status < 400
          ? "redirect-not-followed"
          : "response-received";
      await response.body?.cancel();
    } catch {
      run.state = "request-failed";
    }
    run.completedAt = new Date().toISOString();
    await store.put(key, run);
    return run;
  });
}

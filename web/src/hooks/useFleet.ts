// What each poll asks for, and how often — moved from `App.tsx` verbatim.
//
// Three lists on a four-second timer was 45 requests a minute doing nothing, against a
// default API budget of 120 — more than a third of an operator's allowance spent on an
// idle tab, and enough to start collecting 429s with a second tab open. Two changes.
//
// **Ask for what is on screen.** Permissions and SQL Explorer are not live views, so
// they poll nothing at all; the fleet page asks for both lists it renders.
//
// **Stop asking for `/agents`.** The gateway computes `device.connected` from exactly
// the list that endpoint returns, so fetching both was the same duplication the fleet
// page used to show: one fact, two sources, and a window where they disagree.

import { useCallback, useEffect, useState } from "react";
import { get as getCondition, type Condition } from "@oarlock/terminal/conditions";
import { ApiError, type Client, type Device, type Session } from "../api";

export function useFleet(client: Client, token: string, rendersFleet: boolean) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [me, setMe] = useState("");
  const [listError, setListError] = useState<Condition | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [live, fleet] = await Promise.all([client.sessions(), client.devices()]);
      setSessions(live.sessions);
      setDevices(fleet.devices);
      setListError(null);
      if (live.sessions.length > 0 && !me) setMe(live.sessions[0]!.principal);
    } catch (err) {
      setListError(err instanceof ApiError ? err.condition : getCondition("internal"));
    }
  }, [client, token, me]);

  useEffect(() => {
    void refresh();
    // A page that renders neither list has nothing to poll for. The person page fetches
    // its own, principal-scoped session list instead of reading this one.
    if (!rendersFleet) return;
    const t = setInterval(() => {
      // A background tab polling a rate-limited API is pure waste.
      if (document.hidden) return;
      void refresh();
    }, 4000);
    // A tab coming back to the front is behind by however long it was away, so it asks
    // for everything once rather than waiting out the interval.
    const onVisible = () => {
      if (!document.hidden) void refresh();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [refresh, rendersFleet]);

  return { sessions, devices, me, setMe, listError, refresh };
}

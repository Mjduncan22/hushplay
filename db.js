/*
 * Project Virtue - database client (Supabase REST, no SDK needed)
 *
 *   var db = VirtueDB.create({ supabaseUrl, supabaseKey }, storage)
 *   storage = { get(key) -> Promise<value>, set(key, value) -> Promise }
 *
 * Sign-in is by emailed 6-digit code (no passwords, no redirects), which
 * works the same in the extension, the phone app and the tagger.
 */
(function (root) {
  "use strict";

  function create(cfg, store) {
    cfg = cfg || {};
    var base = String(cfg.supabaseUrl || "").replace(/\/+$/, "");
    var key = cfg.supabaseKey || "";
    var configured = !!(base && key && !/YOUR-PROJECT|PASTE/i.test(base + key));
    var session;   // undefined = not loaded yet, null = signed out

    function need() {
      if (!configured) throw new Error("The database isn't set up yet (fill in config.js).");
    }

    async function loadSession() {
      if (session === undefined) {
        try { session = (await store.get("virtue.session")) || null; } catch (e) { session = null; }
      }
      return session;
    }

    async function saveSession(s) {
      session = s || null;
      try { await store.set("virtue.session", session); } catch (e) {}
    }

    function toSession(d) {
      var now = Math.floor(Date.now() / 1000);
      return {
        access_token: d.access_token,
        refresh_token: d.refresh_token,
        expires_at: d.expires_at || now + (d.expires_in || 3600),
        user: { id: d.user && d.user.id, email: d.user && d.user.email }
      };
    }

    async function http(path, body, bearer) {
      var headers = { "apikey": key, "Content-Type": "application/json" };
      if (bearer) headers.Authorization = "Bearer " + bearer;
      var r = await fetch(base + path, { method: "POST", headers: headers, body: JSON.stringify(body || {}) });
      var text = await r.text(), data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
      if (!r.ok) {
        var msg = (data && (data.message || data.msg || data.error_description || data.error)) || ("HTTP " + r.status);
        var err = new Error(friendly(String(msg)));
        err.status = r.status;
        throw err;
      }
      return data;
    }

    async function httpGet(path, bearer) {
      var r = await fetch(base + path, { headers: { "apikey": key, "Authorization": "Bearer " + bearer } });
      var data = null;
      try { data = await r.json(); } catch (e) {}
      if (!r.ok) throw new Error("That sign-in link didn't work. Request a new one.");
      return data;
    }

    function friendly(msg) {
      if (/token has expired|invalid/i.test(msg) && /otp|token/i.test(msg)) return "That code didn't work or has expired. Request a new one.";
      if (/rate limit/i.test(msg)) return "Too many tries. Wait a minute and try again.";
      if (/sign in first|permission denied for function/i.test(msg)) return "Please sign in first.";
      return msg;
    }

    // A valid access token, refreshing it if it's about to expire.
    async function accessToken() {
      var s = await loadSession();
      if (!s) return null;
      if (Date.now() / 1000 > s.expires_at - 60) {
        try {
          var d = await http("/auth/v1/token?grant_type=refresh_token", { refresh_token: s.refresh_token });
          await saveSession(toSession(d));
          return session.access_token;
        } catch (e) {
          if (e.status === 400 || e.status === 401) await saveSession(null);
          return null;
        }
      }
      return s.access_token;
    }

    async function rpc(fn, args) {
      need();
      return http("/rest/v1/rpc/" + fn, args || {}, await accessToken());
    }

    return {
      configured: configured,

      // redirectTo (optional): where the emailed link should open, e.g. the website's account page.
      sendCode: async function (email, redirectTo) {
        need();
        await http("/auth/v1/otp" + (redirectTo ? "?redirect_to=" + encodeURIComponent(redirectTo) : ""),
          { email: String(email).trim(), create_user: true });
        return true;
      },

      // Accepts any of:
      //  - the 6-digit code (when the email template includes one)
      //  - the "Sign in" link copied from the email (…/auth/v1/verify?token=…&type=…)
      //  - the address the link opened if it was clicked (…#access_token=…&refresh_token=…)
      verifyCode: async function (email, input) {
        need();
        input = String(input || "").trim();
        var d, m;
        if (/access_token=/.test(input)) {
          var p = new URLSearchParams(input.split("#")[1] || input.split("?")[1] || "");
          var at = p.get("access_token");
          var user = await httpGet("/auth/v1/user", at);
          d = { access_token: at, refresh_token: p.get("refresh_token"), expires_in: +p.get("expires_in") || 3600,
            expires_at: +p.get("expires_at") || undefined, user: user };
        } else if ((m = /[?&]token=([^&#\s]+)/.exec(input))) {
          var type = ((/[?&]type=([^&#\s]+)/.exec(input) || [])[1] || "email").toLowerCase();
          if (type === "magiclink" || type === "signup") type = "email";
          d = await http("/auth/v1/verify", { type: type, token_hash: decodeURIComponent(m[1]) });
        } else if (/error_description=/.test(input)) {
          throw new Error("That link has expired or was already used. Request a new one.");
        } else {
          d = await http("/auth/v1/verify", { type: "email", email: String(email).trim(), token: input });
        }
        await saveSession(toSession(d));
        return { email: session.user.email };
      },

      signOut: async function () {
        var s = await loadSession();
        if (s && configured) { try { await http("/auth/v1/logout", {}, s.access_token); } catch (e) {} }
        await saveSession(null);
        return true;
      },

      account: async function () {
        if (!configured) return { configured: false, signedIn: false };
        var t = await accessToken();
        if (!t) return { configured: true, signedIn: false };
        var who = null;
        try { who = await rpc("whoami", {}); } catch (e) {}
        return { configured: true, signedIn: true, email: session.user.email, role: who ? who.role : "member" };
      },

      // Lookups are sent without your sign-in, so what you watch isn't tied to your account.
      // Unverified (not yet reviewed) timestamps come back too, marked, so the app can say so.
      lookup: function (service, serviceId) {
        need();
        return http("/rest/v1/rpc/lookup_title", { p_service: service, p_service_id: String(serviceId),
          p_include_unverified: true }, null);
      },
      signedIn: async function () { return !!(await accessToken()); },
      // Plans & free trial
      config: function () { need(); return http("/rest/v1/rpc/get_config", {}, null); },
      myPlan: function () { return rpc("my_plan", {}); },
      addUsage: function (seconds) { return rpc("add_usage", { p_seconds: Math.round(seconds) }); },
      // Sign in with Google etc.: the address to open. Supabase sends the browser back to
      // redirectTo with #access_token=...; pass that address to verifyCode() to finish.
      oauthUrl: function (provider, redirectTo) {
        need();
        return base + "/auth/v1/authorize?provider=" + encodeURIComponent(provider) +
          "&redirect_to=" + encodeURIComponent(redirectTo);
      },
      // Billing (Supabase Edge Functions): returns { url } to open.
      // plan: "monthly" (default) or "yearly"
      checkout: async function (returnUrl, plan, referralCode) {
        need();
        var body = { return_url: returnUrl, plan: plan === "yearly" ? "yearly" : "monthly" };
        if (referralCode) body.referral_code = String(referralCode).trim().toUpperCase();
        return http("/functions/v1/create-checkout", body, await accessToken());
      },
      billingPortal: async function (returnUrl) {
        need();
        return http("/functions/v1/billing-portal", { return_url: returnUrl }, await accessToken());
      },
      submit: function (service, serviceId, title, segments) {
        return rpc("submit_segments", { p_service: service, p_service_id: String(serviceId),
          p_title: title || {}, p_segments: segments || [] });
      },
      // Filter profiles (only yours; you must be signed in)
      profiles: function () { return rpc("my_profiles", {}); },
      // id null = new profile. name / settings null = keep. makeDefault: true to make it the default.
      saveProfile: function (id, name, settings, makeDefault) {
        return rpc("save_profile", { p_id: id || null, p_name: name == null ? null : String(name),
          p_settings: settings == null ? null : settings, p_default: makeDefault ? true : null });
      },
      deleteProfile: function (id) { return rpc("delete_profile", { p_id: id }); },
      // Referrals: your code and totals; whether a code can be used on your first subscription
      myReferral: function () { return rpc("my_referral", {}); },
      checkReferral: function (code) { return rpc("check_referral_code", { p_code: String(code || "").trim().toUpperCase() }); },
      pending: function (limit) { return rpc("pending_segments", { p_limit: limit || 200 }); },
      review: function (ids, status) { return rpc("review_segments", { p_ids: ids, p_status: status }); },
      vote: function (id, v) { return rpc("vote_segment", { p_id: id, p_vote: v }); }
    };
  }

  var api = { create: create };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.VirtueDB = api;
})(typeof self !== "undefined" ? self : this);

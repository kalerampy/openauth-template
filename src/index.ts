import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";
import { THEME_VERCEL } from "@openauthjs/openauth/ui/theme";
import { MicrosoftProvider } from "@openauthjs/openauth/provider/microsoft";

// This value should be shared between the OpenAuth server Worker and other
// client Workers that you connect to it, so the types and schema validation are
// consistent.
const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // This top section is just for demo purposes. In a real setup another
    // application would redirect the user to this Worker to be authenticated,
    // and after signing in or registering the user would be redirected back to
    // the application they came from. In our demo setup there is no other
    // application, so this Worker needs to do the initial redirect and handle
    // the callback redirect on completion.
    const url = new URL(request.url);
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    } else if (url.pathname === "/callback") {
      return Response.json({
        message: "OAuth flow complete!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    // The real OpenAuth server code starts here:
    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            // eslint-disable-next-line @typescript-eslint/require-await
            sendCode: async (email, code) => {
              // This is where you would email the verification code to the
              // user, e.g. using Resend:
              // https://resend.com/docs/send-with-cloudflare-workers
              console.log(`Sending code ${code} to ${email}`);
            },
            copy: {
              input_code: "Code (check Worker logs)",
            },
          }),
        ),
        microsoft: MicrosoftProvider({
          tenant: "1234567890",
          clientID: "1234567890",
          clientSecret: "0987654321",
          scopes: ["openid", "profile", "email", "offline_access", "User.Read"],
        }),
      },
      theme: THEME_VERCEL,
      success: async (ctx, value) => {
        let email: string;
        if (value.provider === "password") {
          email = value.email;
        } else if (value.provider === "microsoft") {
          email = await getMicrosoftEmail(value.tokenset.access);
        } else {
          throw new Error("Unsupported provider");
        }
        return ctx.subject("user", {
          id: await getOrCreateUser(env, email),
        });
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

async function getOrCreateUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(
    `
		INSERT INTO user (email)
		VALUES (?)
		ON CONFLICT (email) DO UPDATE SET email = email
		RETURNING id;
		`,
  )
    .bind(email)
    .first<{ id: string }>();
  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }
  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}

async function getMicrosoftEmail(accessToken: string): Promise<string> {
  const profileResponse = await fetch(
    "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName",
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );
  if (!profileResponse.ok) {
    throw new Error(
      `Unable to fetch Microsoft profile: ${profileResponse.status}`,
    );
  }
  const profile = await profileResponse.json<{
    mail?: string;
    userPrincipalName?: string;
  }>();
  const email = profile.mail ?? profile.userPrincipalName;
  if (!email) {
    throw new Error("Microsoft profile did not include an email address");
  }
  return email;
}

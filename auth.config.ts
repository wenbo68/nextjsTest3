import type { NextAuthConfig } from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';
import GoogleProvider from 'next-auth/providers/google';
import { signInSchema } from './lib/zod';
import NeonAdapter from "@auth/neon-adapter"
import { Pool } from "@neondatabase/serverless"
import Resend from "next-auth/providers/resend"

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    return undefined;
  }
}

export const authConfig = {
  pages: {
    signIn: '/login',
  },

  callbacks: {

    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith('/dashboard');
      if (isOnDashboard) {
        if (isLoggedIn) return true;
        return false; // Redirect unauthenticated users to login page
      } else if (isLoggedIn) {
        return Response.redirect(new URL('/dashboard', nextUrl));
      }
      return true;
    },
  },

  providers: [

    Credentials({
      credentials: {
        email: {},
        password: {},
      },
      async authorize(credentials) {
        const parseResult = await signInSchema.safeParse(credentials)
        // console.log(parseResult.success);

        if (parseResult.success) {
          const { email, password } = parseResult.data;

          const user = await getUser(email);
          if (!user) return null; //don't return user

          const passwordsMatch = await bcrypt.compare(password, user.password);
          // console.log(passwordsMatch);
          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null; //don't return user
      },
    }),

    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),

    Resend,

  ],

  adapter: NeonAdapter(new Pool({ connectionString: process.env.EMAILMAGICLINK_DATABASE_URL })),

  session: {
    strategy: "database", // Make sure this is set
  },

} satisfies NextAuthConfig;
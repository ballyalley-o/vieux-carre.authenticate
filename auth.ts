  /**
 * NOTE: This file depends on path aliases and modules provided by the consuming/host app.
 * It is not intended to be compiled standalone. All imports below are expected to be resolved
 * by the parent app's tsconfig.json or equivalent module resolution.
 */
  // @ts-nocheck
import { GLOBAL } from 'vieux-carre'
import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import GoogleProvider from 'next-auth/providers/google'
import { cookies } from 'next/headers'
import { compare } from 'lib/encrypt'
import { prisma } from 'db/prisma'
import { KEY } from 'lib/constant'
import { authConfig } from './auth.config'

export type SessionStrategyType = 'jwt' | 'database' | undefined
export const ENVIRONMENT        = GLOBAL.NODE_ENV
export const config             = {
  pages: {
    signIn: '/sign-in',
    error : '/sign-in'
  },
  session: {
    strategy: 'jwt' as const,
    maxAge  : 24 * 60 * 60
  },
  cookies: {
    sessionToken: {
      name   : ENVIRONMENT === 'production' ? '__Secure-next-auth.session-token': 'next-auth.session-token',
      options: {
        domain  : ENVIRONMENT === 'production' ? '.vieuxcarre.app': undefined,
        path    : '/',
        sameSite: 'lax' as const,
        httpOnly: true,
        secure  : ENVIRONMENT === 'production'
      }
    }
  },
  providers: [
    GoogleProvider({
      clientId    : GLOBAL.GOOGLE.CLIENT_ID,
      clientSecret: GLOBAL.GOOGLE.CLIENT_SECRET
    }),
    CredentialsProvider({
      credentials: {
        email   : { type: 'email' },
        password: { type: 'password' }
      },
      async authorize(credentials) {
        if (credentials === null) return null
        const user = await prisma.user.findFirst({
          where: {
            email: credentials.email as string
          }
        })
        if (user && user.password) {
          const isMatch = await compare(credentials.password as string, user.password)
          if (isMatch) {
            return {
              id   : user.id,
              name : user.name,
              email: user.email,
              role : user.role
            }
          }
        }
        return null
      }
    })
  ],
  callbacks: {
    async session({ session, user, trigger, token }: any) {
      session.user.id   = token.sub
      session.user.role = token.role
      session.user.name = token.name
      if (trigger === 'update') {
        session.user.name = user.name
      }
      return session
    },

    async jwt({ token, user, trigger, session }: any) {
      if (user) {
        token.id   = user.id
        token.role = user.role
        if (user.name === 'NO_NAME') {
          token.name = user.email!.split('@')[0]
          await prisma.user.update({ where: { id: user.id }, data: { name: token.name } })
        }
        if ((trigger === 'signIn' || trigger === 'signUp') && user?.id) {
          const cookiesObject = await cookies()
          const sessionBagId  = cookiesObject.get(KEY.SESSION_BAG_ID)?.value

          const dbUser = await prisma.user.findUnique({ where: { id: user.id } })
          if (!dbUser) {
            await prisma.user.create({
              data: {
                id   : user.id,
                name : user.name,
                email: user.email,
                role : user.role
              }
            })
          }

          if (sessionBagId) {
            const sessionBag = await prisma.bag.findFirst({ where: { sessionBagId } })
            if (sessionBag) {
              await prisma.bag.deleteMany({ where: { userId: user.id } })
              await prisma.bag.update({ where: { id: sessionBag.id }, data: { userId: user.id } })
            }
          }
        }
      }
      if (session?.user.name && trigger === 'update') {
        token.name = session.user.name
      }
      return token
    },
    ...(authConfig.callbacks ?? {})
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth(config)

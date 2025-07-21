import bcrypt from 'bcrypt';
import CredentialsProvider from 'next-auth/providers/credentials';
import db from "@repo/db/client";

export const authOptions = {
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                phone: { label: "Phone number", type: "text", placeholder: "123456789", required: true },
                password: { label: "Password", type: "password", required: true }
                // Removed 'name' field since we're not creating users here anymore
            },
            async authorize(credentials: any) {
                if (!credentials?.phone || !credentials?.password) {
                    return null;
                }

                // Only check for existing user - don't create new ones
                const existingUser = await db.user.findFirst({
                    where: {
                        number: credentials.phone
                    }
                });

                if (!existingUser) {
                    return null; // User doesn't exist - they should sign up first
                }

                const passwordValidation = await bcrypt.compare(credentials.password, existingUser.password);
                if (!passwordValidation) {
                    return null; // Wrong password
                }

                return {
                    id: existingUser.id.toString(),
                    name: existingUser.name,
                    email: existingUser.email,
                    number: existingUser.number
                };
            }
        })
    ],
    pages: {
        signIn: '/auth/signin', // Point to your custom sign-in page
    },
    secret: process.env.JWT_SECRET || "secret",
    callbacks: {
        async session({ token, session }: any) {
            session.user.id = token.sub;
            session.user.number = token.number;
            return session;
        },
        async jwt({ token, user }: any) {
            if (user) {
                token.number = user.number;
            }
            return token;
        }
    }
};
import { NextResponse } from 'next/server'
import bcrypt from 'bcrypt'
import db from "@repo/db/client"

export async function POST(request: Request) {
    try {
        const { name, phone, password } = await request.json()

        // Check if user exists
        const existingUser = await db.user.findFirst({
            where: { number: phone }
        })

        if (existingUser) {
            return NextResponse.json({
                error: "User already exists"
            }, { status: 400 })
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10)

        // Create new user
        const user = await db.user.create({
            data: {
                name,
                number: phone,
                password: hashedPassword
            }
        })

        return NextResponse.json({
            message: "User created successfully",
            userId: user.id
        }, { status: 201 })

    } catch (error) {
        console.error(error)
        return NextResponse.json({
            error: "An error occurred while creating the user"
        }, { status: 500 })
    }
}
import { Request, Response } from "express"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import { PrismaClient } from "@prisma/client"
import { enc as encrypt } from "../utils/encrypt"

const prisma = new PrismaClient()
const JWT_SECRET = process.env.JWT_SECRET

export const registerUser = async (req: Request, res: Response) => {
    const {
        name,
        email,
        password,
        consfirmPassword, 
        age,
        number,
        gender,
        country,
        city,
        zipCode
    } = req.body

    if (password !== consfirmPassword) {
        return res.status(400).json({ message: "Passwords do not match" })
    }

    try {
        const existingUser = await prisma.user.findUnique({ where: { email } })
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const encryptedNumber = encrypt(number)
        const encryptedCity = encrypt(city)
        const encryptedZipCode = encrypt(zipCode)

        const newUser = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
                age,
                number: encryptedNumber,
                gender,
                country,
                city: encryptedCity,
                zipCode: encryptedZipCode,
            }
        })

        const token = jwt.sign({ userId: newUser.id }, JWT_SECRET as string, {
            expiresIn: "7d"
        })

        return res.status(201).json({
            message: "User registered successfully",
            token
        })

    } catch (error) {
        console.error("Registration error:", error)
        return res.status(500).json({ message: "Server error" })
    }
}

export const loginUser = async (req: Request, res: Response) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: "Please provide email and password" })
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } })

    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET!, { expiresIn: '7d' })

    return res.status(200).json({ message: "Login successful", token })
  } catch (error) {
    console.error("Login error:", error)
    return res.status(500).json({ message: "Server error" })
  }
}

import crypto from 'crypto'
import dotenv from 'dotenv'

dotenv.config()

const ENC_KEY = process.env.ENC_KEY || "j3Xf9aA1a9zzYAkWj8q4c9paL1QqgO6V"

if (!ENC_KEY || ENC_KEY.length !== 32) {
  throw new Error("ENC_KEY must be defined in .env and must be exactly 32 characters long.")
}

const IV_LENGTH = 16

export function enc(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENC_KEY, 'utf-8'), iv)

  const encrypted = Buffer.concat([
    cipher.update(text, 'utf-8'),
    cipher.final()
  ])
  const tag = cipher.getAuthTag()

  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`
}

export function denc(encryptedText: string): string {
  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted data format');
  }

  const [ivHex, tagHex, encryptedHex] = parts;

  if (!ivHex || !tagHex || !encryptedHex) {
    throw new Error('Missing encrypted components');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENC_KEY, 'utf-8'), iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return decrypted.toString('utf-8');
}


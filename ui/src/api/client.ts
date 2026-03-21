import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL ?? ''
const adminKey = import.meta.env.VITE_ADMIN_KEY ?? ''

export const apiClient = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
    ...(adminKey ? { 'X-Admin-Key': adminKey } : {}),
  },
})

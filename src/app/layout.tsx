import type {Metadata} from 'next';
import './globals.css';
export const metadata:Metadata={title:'Vulnora — Security Intelligence',description:'Security posture and vulnerability intelligence, connected to real evidence.'};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="fa" dir="rtl" suppressHydrationWarning><body>{children}</body></html>;}

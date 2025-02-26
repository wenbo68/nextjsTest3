import { Metadata } from "next";

export const metadata: Metadata = {
    title: 'Customers Page',
    description: 'Details of all Acme customers',
};

export default function Page(){
    return <p>Customers Page</p>
}
import { getServerSession } from "next-auth";
import { authOptions } from "../../lib/auth";
import prisma from "@repo/db/client";
import { AddMoney } from "../../../components/AddMoneyCard";
import { BalanceCard } from "../../../components/BalanceCard";
import { OnRampStatus, OnRampTransaction } from "../../../components/OnRampTransaction";

async function getBalance() {
    const session = await getServerSession(authOptions);
    const balance = await prisma.balance.findFirst({
        where: {
            userId: Number(session?.user?.id)
        }
    });
    return {
        amount: balance?.amount || 0,
        locked: balance?.locked || 0
    }
}

async function getOnRampTransaction() {
    const session = await getServerSession(authOptions);
    const txns = await prisma.onRampTransaction.findMany({
        where: {
            userId: Number(session?.user?.id)
        }
    });

    return txns.map(t => ({
        time: t.startTime,
        amount: t.amount,
        status: t.status as OnRampStatus,
        provider: t.provider
    })).reverse()
}

export default async function() {
    const balance = await getBalance();
    const transactions = await getOnRampTransaction();
 
    return (
        <div className="w-full max-w-full p-4 min-h-screen">
            <div className="text-4xl font-extrabold text-black pt-8 mb-8 ml-5">
                Deposit
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 flex-1 p-4">
                <div>
                    <AddMoney />
                </div>
                <div>
                    <BalanceCard amount={balance.amount} locked={balance.locked} />
                    <div className="mt-5">

                        <OnRampTransaction initialTransactions={transactions} />
                    </div>
                </div>
            </div>
        </div>
    )
}
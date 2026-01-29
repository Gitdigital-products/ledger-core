// TypeScript integration for automatic splits
import { Program, AnchorProvider, web3 } from '@coral-xyz/anchor';
import { FounderLoan } from './types/founder_loan';

export class LoanRepaymentService {
  constructor(
    private program: Program<FounderLoan>,
    private loanAccount: web3.PublicKey,
  ) {}

  async processRevenuePayment(revenueAmount: number) {
    // Calculate 25% for loan repayment
    const repaymentAmount = Math.floor(revenueAmount * 0.25);
    
    // Call auto_repay_from_revenue
    const tx = await this.program.methods
      .autoRepayFromRevenue(new BN(revenueAmount))
      .accounts({
        companyAuthority: this.wallet.publicKey,
        loanAccount: this.loanAccount,
        // ... other accounts
      })
      .rpc();
    
    return tx;
  }
}


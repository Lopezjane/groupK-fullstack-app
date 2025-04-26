import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { AccountService } from '@app/_services';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    accounts: any[] = [];
    loading = true;

    constructor(private accountService: AccountService) {}

    ngOnInit() {
        this.accountService.getAll()
            .pipe(first())
            .subscribe({
                next: accounts => {
                    this.accounts = accounts;
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading accounts:', error);
                    this.loading = false;
                }
            });
    }

    deleteAccount(id: string) {
        const account = this.accounts.find(x => x.id === id);
        if (!account) return;
        
        account.isDeleting = true;
        this.accountService.delete(id)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.accounts = this.accounts.filter(x => x.id !== id);
                },
                error: error => {
                    console.error('Error deleting account:', error);
                    account.isDeleting = false;
                }
            });
    }
}

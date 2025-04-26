import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { AccountService } from '@app/_services';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    accounts: any[] = [];
    filteredAccounts: any[] = [];
    loading = true;

    constructor(private accountService: AccountService) {}

    ngOnInit() {
        this.accountService.getAll()
            .pipe(first())
            .subscribe({
                next: accounts => {
                    this.accounts = accounts;
                    this.filteredAccounts = accounts;
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading accounts:', error);
                    this.loading = false;
                }
            });
    }

    onSearch(term: string) {
        term = term.toLowerCase();
        this.filteredAccounts = this.accounts.filter(account =>
            (`${account.title} ${account.firstName} ${account.lastName}`.toLowerCase().includes(term) ||
            (account.email && account.email.toLowerCase().includes(term)) ||
            (account.firstName && account.firstName.toLowerCase().includes(term)))
        );
    }
}

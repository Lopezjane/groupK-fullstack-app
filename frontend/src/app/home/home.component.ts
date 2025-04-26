import { Component, OnInit } from '@angular/core';

import { AccountService } from '../../app/_services';
import { Role } from '../../app/_models';

@Component({ templateUrl: 'home.component.html' })
export class HomeComponent implements OnInit {
    account: any;
    Role = Role;

    constructor(private accountService: AccountService) {}
    
    ngOnInit() {
        this.accountService.account.subscribe(x => {
            this.account = x;
        });
    }
}
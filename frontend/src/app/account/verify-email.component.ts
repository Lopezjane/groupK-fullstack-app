import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { first } from 'rxjs/operators';

import { AccountService, AlertService } from '@app/_services';

@Component({ templateUrl: 'verify-email.component.html' })
export class VerifyEmailComponent implements OnInit {
    token: string;

    constructor(
        private route: ActivatedRoute,
        private router: Router,
        private accountService: AccountService,
        private alertService: AlertService
    ) { }

    ngOnInit() {
        this.token = this.route.snapshot.queryParams['token'];

        // remove token from url to prevent http referer leakage
        this.router.navigate([], { relativeTo: this.route, replaceUrl: true });

        this.accountService.verifyEmail(this.token)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.alertService.success('Verification successful, you can now login', { keepAfterRouteChange: true });
                    this.router.navigate(['../login'], { relativeTo: this.route });
                },
                error: error => {
                    this.alertService.error(error);
                }
            });
    }
} 
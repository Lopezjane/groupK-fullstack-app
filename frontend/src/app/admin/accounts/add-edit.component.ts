import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { first } from 'rxjs/operators';

import { AccountService, AlertService } from '@app/_services';
import { Role } from '@app/_models';
import { MustMatch } from '@app/_helpers';

@Component({ templateUrl: 'add-edit.component.html' })
export class AddEditComponent implements OnInit {
    form: FormGroup;
    id: string;
    isAddMode: boolean;
    loading = false;
    submitted = false;
    isAdmin = false;

    constructor(
        private formBuilder: FormBuilder,
        private route: ActivatedRoute,
        private router: Router,
        private accountService: AccountService,
        private alertService: AlertService
    ) {}

    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        this.isAddMode = !this.id;
        
        // Check if current user is admin
        this.isAdmin = this.accountService.accountValue?.role === Role.Admin;
        
        const passwordValidators = [Validators.minLength(6)];
        if (this.isAddMode) {
            passwordValidators.push(Validators.required);
        }

        // Initialize form
        this.form = this.formBuilder.group({
            title: ['', Validators.required],
            firstName: ['', Validators.required],
            lastName: ['', Validators.required],
            email: ['', [Validators.required, Validators.email]],
            password: ['', passwordValidators],
            confirmPassword: ['', this.isAddMode ? Validators.required : Validators.nullValidator],
            role: [Role.User, Validators.required]
        }, {
            validator: MustMatch('password', 'confirmPassword')
        });

        // Add status field for admin users in edit mode
        if (!this.isAddMode && this.isAdmin) {
            this.form.addControl('status', this.formBuilder.control('', Validators.required));
        }

        // Load account data in edit mode
        if (!this.isAddMode) {
            console.log('Loading account with ID:', this.id);
            this.accountService.getById(this.id)
                .pipe(first())
                .subscribe({
                    next: account => {
                        console.log('Account loaded successfully:', account);
                        this.form.patchValue(account);
                    },
                    error: error => {
                        console.error('Error loading account:', error);
                        this.alertService.error('Error loading account: ' + (error.message || JSON.stringify(error)));
                        this.router.navigate(['/admin/accounts']);
                    }
                });
        }
    }

    // convenience getter for easy access to form fields
    get f() { return this.form.controls; }

    onSubmit() {
        this.submitted = true;

        // reset alerts on submit
        this.alertService.clear();

        // stop here if form is invalid
        if (this.form.invalid) {
            return;
        }

        this.loading = true;
        if (this.isAddMode) {
            this.createAccount();
        } else {
            this.updateAccount();
        }
    }

    private createAccount() {
        this.accountService.create(this.form.value)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.alertService.success('Account created successfully', { keepAfterRouteChange: true });
                    this.router.navigate(['../'], { relativeTo: this.route });
                },
                error: error => {
                    this.alertService.error(error);
                    this.loading = false;
                }
            });
    }

    private updateAccount() {
        // Prepare update payload - only admin can update status
        const updatePayload = { ...this.form.value };
        if (!this.isAdmin) {
            delete updatePayload.status;
        }
        
        this.accountService.update(this.id, updatePayload)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.alertService.success('Update successful', { keepAfterRouteChange: true });
                    this.router.navigate(['../../'], { relativeTo: this.route });
                },
                error: error => {
                    this.alertService.error(error);
                    this.loading = false;
                }
            });
    }
}

import { NgModule } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { LayoutComponent } from './layout.component';
import { ListComponent } from './list.component';
import { AddEditComponent } from './add-edit.component';

@NgModule({
    imports: [
        CommonModule,
        ReactiveFormsModule,
        RouterModule.forChild([
            {
                path: '', component: LayoutComponent,
                children: [
                    { path: '', component: ListComponent },
                    { path: 'add', component: AddEditComponent },
                    { path: 'edit/:id', component: AddEditComponent }
                ]
            }
        ])
    ],
    declarations: [
        LayoutComponent,
        ListComponent,
        AddEditComponent
    ]
})
export class AccountsModule { } 
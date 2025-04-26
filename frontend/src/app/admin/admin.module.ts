import { NgModule } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { AdminRoutingModule } from './admin-routing.module';
import { LayoutComponent } from './layout.component';
import { OverViewComponent } from './overview.component';

@NgModule({
  imports: [
    CommonModule,
    ReactiveFormsModule,
    AdminRoutingModule
  ],
  declarations: [
    LayoutComponent,
    OverViewComponent
  ]
})
export class AdminModule { }

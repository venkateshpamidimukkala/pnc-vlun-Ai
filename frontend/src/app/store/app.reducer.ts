import { createReducer, on } from '@ngrx/store';
import { createAction, props } from '@ngrx/store';

export interface AppState { selectedMnemonic: string | null; }
export const selectMnemonic = createAction('[Context] Select Mnemonic', props<{ mnemonic: string | null }>());
export const appReducer = createReducer<AppState>({ selectedMnemonic: null }, on(selectMnemonic, (state, action) => ({ ...state, selectedMnemonic: action.mnemonic })));

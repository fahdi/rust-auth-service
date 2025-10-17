import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const response = await fetch('http://localhost:8080/health');
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const healthData = await response.json();
    
    return NextResponse.json({
      success: true,
      message: 'Successfully connected to Rust Auth Service',
      data: healthData
    });
  } catch (error) {
    return NextResponse.json({
      success: false,
      message: error instanceof Error ? error.message : 'Unknown error',
      data: null
    }, { status: 500 });
  }
}